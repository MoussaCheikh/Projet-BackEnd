<?php
session_start();
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Générer le token CSRF s'il n'existe pas encore
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Configuration de la base de données
$servername  = "localhost";
$username_db = "root";
$password_db = "";
$dbname      = "gestion_users";

// Connexion MySQLi
$conn = new mysqli($servername, $username_db, $password_db, $dbname);
if ($conn->connect_error) {
    die("Échec de connexion: " . $conn->connect_error);
}

// Fonction pour hacher les mots de passe
function hashPassword($password) {
    return password_hash($password, PASSWORD_BCRYPT);
}

// Vérification du token CSRF pour toute requête POST
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die("Erreur CSRF détectée.");
    }
}

if (isset($_POST['login'])) {
    $login_username = trim($_POST['login_username'] ?? '');
    $login_password = trim($_POST['login_password'] ?? '');
    
    if (empty($login_username) || empty($login_password)) {
        $login_error = "Veuillez remplir tous les champs.";
    } else {
        // Vérification pour l'administrateur
        if ($login_username === 'admin' && $login_password === 'admin') {
            $_SESSION['user_id']      = 0;
            $_SESSION['display_name'] = 'Administrateur';
            $_SESSION['logged_in']    = true;
        } else {
            // Vérification pour les utilisateurs normaux (dans la base)
            $stmt = $conn->prepare("SELECT id, nom, prenom, password, photo FROM utilisateurs WHERE login = ?");
            $stmt->bind_param("s", $login_username);
            $stmt->execute();
            $result = $stmt->get_result();
            if ($result->num_rows === 1) {
                $row = $result->fetch_assoc();
                if (password_verify($login_password, $row['password'])) {
                    $_SESSION['user_id']      = $row['id'];
                    $_SESSION['display_name'] = $row['prenom'] . ' ' . $row['nom'];
                    $_SESSION['user_photo']   = !empty($row['photo'])
                        ? $row['photo']
                        : 'https://via.placeholder.com/50?text=User';
                    $_SESSION['logged_in']    = true;
                } else {
                    $login_error = "Identifiants incorrects";
                }
            } else {
                $login_error = "Identifiants incorrects";
            }
        }
    }
}

// Déconnexion
if (isset($_GET['logout'])) {
    session_destroy();
    header("Location: index.php");
    exit();
}


// Ajout d'un utilisateur (admin uniquement)
if (isset($_POST['add_user'])) {
    if (!isset($_SESSION['display_name']) || $_SESSION['display_name'] !== 'Administrateur') {
        die("Vous n'avez pas les droits pour ajouter des utilisateurs.");
    }
    
    $nom    = $conn->real_escape_string($_POST['nom']);
    $prenom = $conn->real_escape_string($_POST['prenom']);
    $login  = $conn->real_escape_string($_POST['login']);
    $password_hashed = hashPassword($conn->real_escape_string($_POST['password']));
    
    // Vérifier si le login existe déjà
    $stmt_check = $conn->prepare("SELECT COUNT(*) AS count FROM utilisateurs WHERE login = ?");
    $stmt_check->bind_param("s", $login);
    $stmt_check->execute();
    $result_check = $stmt_check->get_result();
    $row_check = $result_check->fetch_assoc();
    if ($row_check['count'] > 0) {
        $error_message = "Le login existe déjà. Veuillez choisir un autre login.";
    } else {
        // Traitement de l'image (optionnel)
        $photo = "";
        if (isset($_FILES['photo']) && $_FILES['photo']['error'] == 0) {
            $dossier_upload = "uploads/";
            if (!is_dir($dossier_upload)) { mkdir($dossier_upload, 0777, true); }
            $allowed_extensions = ['jpg', 'jpeg', 'png', 'gif'];
            $file_info = pathinfo($_FILES['photo']['name']);
            $extension = strtolower($file_info['extension'] ?? '');
            if (!in_array($extension, $allowed_extensions)) {
                $upload_error = "Erreur: Format de fichier non autorisé.";
            } elseif ($_FILES['photo']['size'] > 5 * 1024 * 1024) {
                $upload_error = "Erreur: La taille du fichier dépasse la limite autorisée.";
            } else {
                $nouveau_nom_photo = uniqid() . '.' . $extension;
                $chemin_photo = $dossier_upload . $nouveau_nom_photo;
                if (move_uploaded_file($_FILES['photo']['tmp_name'], $chemin_photo)) {
                    $photo = $chemin_photo;
                } else {
                    $upload_error = "Erreur lors du téléchargement de l'image.";
                }
            }
        }
        
        if (!isset($upload_error)) {
            $stmt = $conn->prepare("INSERT INTO utilisateurs (nom, prenom, login, password, photo) VALUES (?, ?, ?, ?, ?)");
            $stmt->bind_param("sssss", $nom, $prenom, $login, $password_hashed, $photo);
            if ($stmt->execute()) {
                $success_message = "Utilisateur ajouté avec succès";
            } else {
                $error_message = "Erreur: " . $stmt->error;
            }
        }
    }
}

// Suppression d'un utilisateur (admin uniquement)
if (isset($_GET['delete']) && isset($_SESSION['logged_in'])) {
    if ($_SESSION['display_name'] !== 'Administrateur') {
        die("Vous n'avez pas les droits pour effectuer cette action.");
    }
    $id = intval($_GET['delete']);
    
    // Supprimer la photo associée si elle existe
    $stmt = $conn->prepare("SELECT photo FROM utilisateurs WHERE id = ?");
    $stmt->bind_param("i", $id);
    $stmt->execute();
    $result = $stmt->get_result();
    if ($result->num_rows === 1) {
        $row = $result->fetch_assoc();
        if (!empty($row['photo']) && file_exists($row['photo'])) {
            unlink($row['photo']);
        }
    }
    
    $stmt = $conn->prepare("DELETE FROM utilisateurs WHERE id = ?");
    $stmt->bind_param("i", $id);
    if ($stmt->execute()) {
        $success_message = "Utilisateur supprimé avec succès";
    } else {
        $error_message = "Erreur: " . $stmt->error;
    }
    
    // Réinitialiser l'auto-increment si la table est vide
    $res_count = $conn->query("SELECT COUNT(*) as count FROM utilisateurs");
    $row_count = $res_count->fetch_assoc();
    if ($row_count['count'] == 0) {
        $conn->query("ALTER TABLE utilisateurs AUTO_INCREMENT = 1");
    }
}

// Mise à jour d'un utilisateur (admin uniquement)
if (isset($_POST['update_user']) && isset($_SESSION['logged_in'])) {
    if ($_SESSION['display_name'] !== 'Administrateur') {
        die("Vous n'avez pas les droits pour effectuer cette action.");
    }
    $id = intval($_POST['id']);
    $nom    = $conn->real_escape_string($_POST['nom']);
    $prenom = $conn->real_escape_string($_POST['prenom']);
    $login  = $conn->real_escape_string($_POST['login']);
    
    $params = [$nom, $prenom, $login];
    $types  = "sss";
    $update_fields = "nom = ?, prenom = ?, login = ?";
    
    if (!empty($_POST['password'])) {
        $password_hashed = password_hash($_POST['password'], PASSWORD_BCRYPT);
        $update_fields .= ", password = ?";
        $params[] = $password_hashed;
        $types .= "s";
    }
    
    if (isset($_FILES['photo']) && $_FILES['photo']['error'] == 0) {
        $dossier_upload = "uploads/";
        if (!is_dir($dossier_upload)) { mkdir($dossier_upload, 0777, true); }
        $allowed_extensions = ['jpg', 'jpeg', 'png', 'gif'];
        $file_info = pathinfo($_FILES['photo']['name']);
        $extension = strtolower($file_info['extension'] ?? '');
        if (!in_array($extension, $allowed_extensions)) {
            $upload_error = "Erreur: Format de fichier non autorisé.";
        } elseif ($_FILES['photo']['size'] > 5 * 1024 * 1024) {
            $upload_error = "Erreur: La taille du fichier dépasse la limite autorisée.";
        } else {
            $nouveau_nom_photo = uniqid() . '.' . $extension;
            $chemin_photo = $dossier_upload . $nouveau_nom_photo;
            if (move_uploaded_file($_FILES['photo']['tmp_name'], $chemin_photo)) {
                $update_fields .= ", photo = ?";
                $params[] = $chemin_photo;
                $types .= "s";
            } else {
                $upload_error = "Erreur lors du téléchargement de l'image.";
            }
        }
    }
    
    if (!isset($upload_error)) {
        $update_sql = "UPDATE utilisateurs SET $update_fields WHERE id = ?";
        $params[] = $id;
        $types .= "i";
        $stmt = $conn->prepare($update_sql);
        $stmt->bind_param($types, ...$params);
        if ($stmt->execute()) {
            // Rediriger vers la page d'accueil après la mise à jour réussie
            header("Location: index.php");
            exit();
        } else {
            $error_message = "Erreur lors de la mise à jour: " . $stmt->error;
        }
    }
}

// Préparation pour l'édition d'un utilisateur (admin uniquement)
if (isset($_GET['edit']) && isset($_SESSION['logged_in'])) {
    if ($_SESSION['display_name'] !== 'Administrateur') {
        die("Vous n'avez pas les droits pour éditer un utilisateur.");
    }
    $id = intval($_GET['edit']);
    $stmt = $conn->prepare("SELECT * FROM utilisateurs WHERE id = ?");
    $stmt->bind_param("i", $id);
    $stmt->execute();
    $result = $stmt->get_result();
    if ($result->num_rows === 1) {
        $user_to_edit = $result->fetch_assoc();
    }
}


$users = [];
if (isset($_SESSION['logged_in'])) {
    $res = $conn->query("SELECT * FROM utilisateurs");
    if ($res && $res->num_rows > 0) {
        while ($row = $res->fetch_assoc()) {
            $users[] = $row;
        }
    }
}
?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>Gestion des Utilisateurs</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.5/font/bootstrap-icons.css">
    <style>
        .profile-img {
            width: 50px;
            height: 50px;
            object-fit: cover;
            border-radius: 50%;
        }
        .flash-msg { transition: opacity 0.5s ease; }
    </style>
</head>
<body class="bg-light">
<div class="container mt-4">
    <h1 class="text-center mb-4">Gestion des Utilisateurs</h1>
    
    <?php if (isset($error_message)): ?>
        <div class="alert alert-danger flash-msg"><?php echo $error_message; ?></div>
    <?php endif; ?>
    <?php if (isset($success_message)): ?>
        <div class="alert alert-success flash-msg"><?php echo $success_message; ?></div>
    <?php endif; ?>
    <?php if (isset($upload_error)): ?>
        <div class="alert alert-warning flash-msg"><?php echo $upload_error; ?></div>
    <?php endif; ?>
    
    <script>
        setTimeout(function() {
            document.querySelectorAll('.flash-msg').forEach(function(el) {
                el.style.opacity = '0';
            });
        }, 3000);
    </script>
    
    <?php if (!isset($_SESSION['logged_in'])): ?>
        <div class="mx-auto" style="max-width: 400px;">
            <h2 class="text-center mb-4">Connexion</h2>
            <?php if (isset($login_error)): ?>
                <div class="alert alert-danger flash-msg"><?php echo $login_error; ?></div>
            <?php endif; ?>
            <form method="post" action="">
                <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                <div class="mb-3">
                    <label for="login_username" class="form-label">Nom d'utilisateur</label>
                    <input type="text" class="form-control" id="login_username" name="login_username" value="admin" required>
                </div>
                <div class="mb-3">
                    <label for="login_password" class="form-label">Mot de passe</label>
                    <input type="password" class="form-control" id="login_password" name="login_password" value="admin" required>
                </div>
                <button type="submit" name="login" class="btn btn-primary w-100">Se connecter</button>
            </form>
        </div>
    <?php else: ?>
        <div class="d-flex justify-content-between align-items-center mb-4">
            <div>
                Connecté en tant que: <strong><?php echo $_SESSION['display_name']; ?></strong><br>
                <?php if ($_SESSION['display_name'] === 'Administrateur'): ?>
                    <i class="bi bi-person-circle" style="font-size:50px;"></i>
                <?php else: ?>
                    <img src="<?php echo $_SESSION['user_photo'] ?? 'https://via.placeholder.com/50?text=User'; ?>" alt="Photo de profil" class="profile-img mt-2">
                <?php endif; ?>
            </div>
            <a href="?logout=1" class="btn btn-danger">Déconnexion</a>
        </div>
        
        <?php if ($_SESSION['display_name'] === 'Administrateur'): ?>
            <div class="mb-5">
                <h2 class="mb-3"><?php echo isset($user_to_edit) ? 'Modifier' : 'Ajouter'; ?> un utilisateur</h2>
                <form method="post" action="" enctype="multipart/form-data">
                    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                    <?php if (isset($user_to_edit)): ?>
                        <input type="hidden" name="id" value="<?php echo $user_to_edit['id']; ?>">
                    <?php endif; ?>
                    
                    <div class="row mb-3">
                        <div class="col">
                            <label for="nom" class="form-label">Nom</label>
                            <input type="text" class="form-control" id="nom" name="nom"
                                   value="<?php echo isset($user_to_edit) ? $user_to_edit['nom'] : ''; ?>" required>
                        </div>
                        <div class="col">
                            <label for="prenom" class="form-label">Prénom</label>
                            <input type="text" class="form-control" id="prenom" name="prenom"
                                   value="<?php echo isset($user_to_edit) ? $user_to_edit['prenom'] : ''; ?>" required>
                        </div>
                    </div>
                    
                    <div class="mb-3">
                        <label for="login" class="form-label">Nom d'utilisateur</label>
                        <input type="text" class="form-control" id="login" name="login"
                               value="<?php echo isset($user_to_edit) ? $user_to_edit['login'] : ''; ?>" required>
                    </div>
                    
                    <div class="mb-3">
                        <label for="password" class="form-label">
                            Mot de passe <?php echo isset($user_to_edit) ? '(laisser vide pour conserver l\'actuel)' : ''; ?>
                        </label>
                        <input type="password" class="form-control" id="password" name="password"
                               <?php echo isset($user_to_edit) ? '' : 'required'; ?>>
                    </div>
                    
                    <div class="mb-3">
                        <label for="photo" class="form-label">Photo de profil</label>
                        <input type="file" name="photo" accept="image/*">
                        <?php if (isset($user_to_edit) && !empty($user_to_edit['photo'])): ?>
                            <div class="mt-2">
                                <small>Photo actuelle:</small>
                                <img src="<?php echo $user_to_edit['photo']; ?>" alt="Photo de profil" class="profile-img ms-2">
                            </div>
                        <?php endif; ?>
                    </div>
                    
                    <button type="submit" name="<?php echo isset($user_to_edit) ? 'update_user' : 'add_user'; ?>" class="btn btn-primary">
                        <?php echo isset($user_to_edit) ? 'Mettre à jour' : 'Ajouter'; ?>
                    </button>
                    
                    <?php if (isset($user_to_edit)): ?>
                        <a href="index.php" class="btn btn-secondary ms-2">Annuler</a>
                    <?php endif; ?>
                </form>
            </div>
        <?php endif; ?>
        
        <h2 class="mb-3">Liste des utilisateurs</h2>
        <div class="table-responsive">
            <table class="table table-striped table-hover">
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Photo</th>
                        <th>Nom</th>
                        <th>Prénom</th>
                        <th>Login</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if (!empty($users)): ?>
                        <?php foreach ($users as $user): ?>
                            <tr>
                                <td><?php echo $user['id']; ?></td>
                                <td>
                                    <?php if (!empty($user['photo'])): ?>
                                        <img src="<?php echo $user['photo']; ?>" alt="Photo de profil" class="profile-img">
                                    <?php else: ?>
                                        <img src="https://via.placeholder.com/50?text=User" alt="Placeholder" class="profile-img">
                                    <?php endif; ?>
                                </td>
                                <td><?php echo $user['nom']; ?></td>
                                <td><?php echo $user['prenom']; ?></td>
                                <td><?php echo $user['login']; ?></td>
                                <td>
                                    <?php if ($_SESSION['display_name'] === 'Administrateur'): ?>
                                        <a href="?edit=<?php echo $user['id']; ?>" class="btn btn-sm btn-warning">Modifier</a>
                                        <a href="?delete=<?php echo $user['id']; ?>" class="btn btn-sm btn-danger" onclick="return confirm('Êtes-vous sûr de vouloir supprimer cet utilisateur?')">Supprimer</a>
                                    <?php else: ?>
                                    <?php endif; ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    <?php else: ?>
                        <tr>
                            <td colspan="6" class="text-center">Aucun utilisateur trouvé</td>
                        </tr>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
    <?php endif; ?>
</div>
<script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap/5.3.0/js/bootstrap.bundle.min.js"></script>
</body>
</html>
