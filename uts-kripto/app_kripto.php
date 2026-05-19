<?php
class KriptoTools {
    // 1. CAESAR CIPHER
    public static function caesarCipher($text, $shift, $decrypt = false) {
        $result = '';
        $shift = (int)$shift;
        $shift = $decrypt ? (26 - ($shift % 26)) : ($shift % 26);
        
        for ($i = 0; $i < strlen($text); $i++) {
            $char = $text[$i];
            if (ctype_alpha($char)) {
                $asciiOffset = ctype_upper($char) ? 65 : 97;
                $result .= chr((ord($char) - $asciiOffset + $shift) % 26 + $asciiOffset);
            } else {
                $result .= $char;
            }
        }
        return $result;
    }

    // 2. XOR CIPHER
    public static function xorEncrypt($text, $key) {
        $result = '';
        $keyLen = strlen($key);
        if ($keyLen === 0) return base64_encode($text);
        
        for ($i = 0; $i < strlen($text); $i++) {
            $result .= $text[$i] ^ $key[$i % $keyLen];
        }
        return base64_encode($result);
    }

    public static function xorDecrypt($base64Text, $key) {
        $text = base64_decode($base64Text);
        $result = '';
        $keyLen = strlen($key);
        if ($keyLen === 0) return $text;
        
        for ($i = 0; $i < strlen($text); $i++) {
            $result .= $text[$i] ^ $key[$i % $keyLen];
        }
        return $result;
    }

    // 3. SHA-256 HASH
    public static function sha256Hash($text) {
        return hash('sha256', $text);
    }

    // 4. RSA (ENKRIPSI, DEKRIPSI, & SIGNATURE)
    public static function getRSAConfig() {
        $config = array(
            "digest_alg" => "sha256",
            "private_key_bits" => 2048,
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
        );

        $confPaths = array(
            'C:/xampp/php/extras/ssl/openssl.cnf',
            'C:/xampp/apache/conf/openssl.cnf',
            'D:/xampp/php/extras/ssl/openssl.cnf',
            'D:/xampp/apache/conf/openssl.cnf',
        );

        foreach ($confPaths as $path) {
            if (file_exists($path)) {
                $config["config"] = $path;
                break;
            }
        }
        return $config;
    }

    public static function generateRSAKeys() {
        $config = self::getRSAConfig();
        $res = openssl_pkey_new($config);
        if (!$res) return false;
        openssl_pkey_export($res, $privKey, null, $config);
        $pubKeyDetails = openssl_pkey_get_details($res);
        $pubKey = $pubKeyDetails["key"];
        return array('private_key' => $privKey, 'public_key' => $pubKey);
    }

    public static function rsaEncrypt($text, $publicKey) {
        $keyResource = @openssl_pkey_get_public($publicKey);
        if (!$keyResource) return false;
        
        if (@openssl_public_encrypt($text, $encrypted, $keyResource)) {
            return base64_encode($encrypted);
        }
        return false;
    }

    public static function rsaDecrypt($encryptedBase64, $privateKey) {
        $keyResource = @openssl_pkey_get_private($privateKey);
        if (!$keyResource) return false;
        
        if (@openssl_private_decrypt(base64_decode($encryptedBase64), $decrypted, $keyResource)) {
            return $decrypted;
        }
        return false;
    }

    public static function rsaSign($text, $privateKey) {
        $keyResource = @openssl_pkey_get_private($privateKey);
        if (!$keyResource) return false;
        
        if (@openssl_sign($text, $signature, $keyResource, OPENSSL_ALGO_SHA256)) {
            return base64_encode($signature);
        }
        return false;
    }

    public static function rsaVerify($text, $signatureBase64, $publicKey) {
        $keyResource = @openssl_pkey_get_public($publicKey);
        if (!$keyResource) return false;
        
        $isValid = @openssl_verify($text, base64_decode($signatureBase64), $keyResource, OPENSSL_ALGO_SHA256);
        return $isValid === 1;
    }
}

// Menangani Request
$activeTab = $_POST['tab'] ?? $_POST['current_tab'] ?? 'caesar';
$textInput = $_POST['text'] ?? '';
$action = $_POST['action'] ?? 'encrypt';
$result = '';
$error = '';
$shift = $_POST['shift'] ?? 3;
$xorKey = $_POST['xor_key'] ?? '';
$rsaPublicKey = $_POST['rsa_public_key'] ?? '';
$rsaPrivateKey = $_POST['rsa_private_key'] ?? '';
$signatureInput = $_POST['signature_input'] ?? '';

// Generate RSA Keys if requested
if (isset($_POST['generate_keys'])) {
    $keys = KriptoTools::generateRSAKeys();
    if ($keys) {
        $rsaPublicKey = $keys['public_key'];
        $rsaPrivateKey = $keys['private_key'];
        $result = "Kunci RSA berhasil dibuat secara otomatis!";
    } else {
        $error = "Gagal membuat kunci RSA. Pastikan OpenSSL terkonfigurasi di PHP (openssl.cnf).";
    }
    $activeTab = 'rsa';
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    try {
        if ($activeTab === 'caesar') {
            $result = KriptoTools::caesarCipher($textInput, $shift, $action === 'decrypt');
        } elseif ($activeTab === 'xor') {
            if ($action === 'encrypt') {
                $result = KriptoTools::xorEncrypt($textInput, $xorKey);
            } else {
                $result = KriptoTools::xorDecrypt($textInput, $xorKey);
            }
        } elseif ($activeTab === 'hash') {
            $result = KriptoTools::sha256Hash($textInput);
        } elseif ($activeTab === 'rsa') {
            if ($action === 'encrypt') {
                $res = KriptoTools::rsaEncrypt($textInput, $rsaPublicKey);
                if ($res) $result = $res;
                else $error = "Gagal mengenkripsi! Pastikan Public Key yang dimasukkan valid.";
            } elseif ($action === 'decrypt') {
                $res = KriptoTools::rsaDecrypt($textInput, $rsaPrivateKey);
                if ($res) $result = $res;
                else $error = "Gagal mendekripsi! Pastikan Private Key benar dan Base64 valid.";
            }
        } elseif ($activeTab === 'signature') {
            if ($action === 'sign') {
                $res = KriptoTools::rsaSign($textInput, $rsaPrivateKey);
                if ($res) $result = $res;
                else $error = "Gagal membuat signature! Pastikan Private Key valid.";
            } elseif ($action === 'verify') {
                $isValid = KriptoTools::rsaVerify($textInput, $signatureInput, $rsaPublicKey);
                if ($isValid) {
                    $result = "VERIFICATION PASSED: Tanda tangan cocok. Sumber otentik & tidak diubah.";
                } else {
                    $error = "VERIFICATION FAILED: Tanda tangan tidak valid atau data sudah diubah!";
                }
            }
        }
    } catch (Exception $e) {
        $error = "Terjadi sistem error: " . $e->getMessage();
    }
}
?>
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CryptoLens | Minimal Security Engine</title>
    <!-- Tailwind CSS CDN -->
    <script src="https://cdn.tailwindcss.com"></script>
    <!-- Phosphor Icons -->
    <script src="https://unpkg.com/@phosphor-icons/web"></script>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Plus+Jakarta+Sans:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <script>
        tailwind.config = {
            theme: {
                extend: {
                    fontFamily: {
                        sans: ['"Plus Jakarta Sans"', 'sans-serif'],
                        mono: ['JetBrains Mono', 'monospace'],
                    },
                    colors: {
                        gray: {
                            850: '#1f2937',
                            900: '#111827',
                            950: '#0a0a0f',
                        },
                        brand: {
                            400: '#818cf8',
                            500: '#6366f1',
                            600: '#4f46e5',
                        }
                    }
                }
            }
        }
    </script>
    <style>
        body { background-color: #0a0a0f; color: #f3f4f6; }
        
        /* Subtle Grid Background */
        .bg-grid {
            background-size: 30px 30px;
            background-image: 
                linear-gradient(to right, rgba(255, 255, 255, 0.03) 1px, transparent 1px),
                linear-gradient(to bottom, rgba(255, 255, 255, 0.03) 1px, transparent 1px);
        }

        .glass-card {
            background: rgba(20, 20, 25, 0.6);
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
            border: 1px solid rgba(255, 255, 255, 0.05);
            box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.3);
        }
        
        .nav-item {
            position: relative;
            overflow: hidden;
        }
        
        .nav-item.active {
            background: rgba(99, 102, 241, 0.1);
            color: #818cf8;
            border-right: 3px solid #6366f1;
        }
        
        .nav-item.active::before {
            content: '';
            position: absolute;
            left: 0; top: 0; bottom: 0; width: 40px;
            background: linear-gradient(90deg, rgba(99,102,241,0.2) 0%, transparent 100%);
        }

        .custom-scrollbar::-webkit-scrollbar { width: 5px; height: 5px; }
        .custom-scrollbar::-webkit-scrollbar-track { background: transparent; }
        .custom-scrollbar::-webkit-scrollbar-thumb { background: #27272a; border-radius: 10px; }
        .custom-scrollbar::-webkit-scrollbar-thumb:hover { background: #3f3f46; }
        
        .glow-text { text-shadow: 0 0 20px rgba(99, 102, 241, 0.5); }
        .input-focus-glow:focus { box-shadow: 0 0 0 2px rgba(99, 102, 241, 0.4); border-color: transparent; }
        
        @keyframes slideUpFade {
            0% { opacity: 0; transform: translateY(10px); }
            100% { opacity: 1; transform: translateY(0); }
        }
        .animate-enter { animation: slideUpFade 0.5s cubic-bezier(0.16, 1, 0.3, 1) forwards; }
    </style>
</head>
<body class="flex h-screen overflow-hidden font-sans selection:bg-brand-500 selection:text-white bg-grid">

    <!-- Ambient Background Effects -->
    <div class="fixed top-[-20%] right-[-10%] w-[600px] h-[600px] rounded-full bg-brand-600/10 blur-[120px] pointer-events-none z-0"></div>
    <div class="fixed bottom-[-10%] left-[-10%] w-[600px] h-[600px] rounded-full bg-purple-600/10 blur-[120px] pointer-events-none z-0"></div>

    <!-- Desktop Sidebar -->
    <aside class="w-72 flex-shrink-0 flex flex-col border-r border-gray-800/80 bg-gray-900/60 backdrop-blur-2xl z-20 hidden md:flex transition-all">
        <div class="h-24 flex items-center px-8 border-b border-gray-800/80">
            <div class="flex items-center gap-4">
                <div class="w-12 h-12 rounded-2xl bg-gradient-to-br from-brand-400 to-brand-600 flex items-center justify-center shadow-[0_0_24px_rgba(99,102,241,0.4)] border border-brand-400/30">
                    <i class="ph-duotone ph-shield-check text-white text-2xl"></i>
                </div>
                <div>
                    <h1 class="text-xl font-bold tracking-tight text-white glow-text">CryptoLens</h1>
                    <p class="text-[10px] uppercase tracking-widest text-brand-400 font-mono mt-0.5">Security Engine</p>
                </div>
            </div>
        </div>
        
        <form method="POST" action="" class="flex-1 overflow-y-auto custom-scrollbar py-6 flex flex-col gap-1.5">
            <p class="px-8 text-[10px] font-bold text-gray-500 uppercase tracking-[0.2em] mb-4 mt-2">Tools Menu</p>
            
            <button type="submit" name="tab" value="caesar" class="nav-item flex items-center gap-4 px-8 py-3.5 text-sm font-medium text-gray-400 hover:text-gray-200 hover:bg-gray-800/40 transition-all text-left w-full <?= $activeTab=='caesar'?'active':'' ?>">
                <i class="ph-duotone ph-text-aa w-5 text-xl <?= $activeTab=='caesar'?'text-brand-400':'' ?>"></i> Caesar Cipher
            </button>
            <button type="submit" name="tab" value="xor" class="nav-item flex items-center gap-4 px-8 py-3.5 text-sm font-medium text-gray-400 hover:text-gray-200 hover:bg-gray-800/40 transition-all text-left w-full <?= $activeTab=='xor'?'active':'' ?>">
                <i class="ph-duotone ph-arrows-left-right w-5 text-xl <?= $activeTab=='xor'?'text-purple-400':'' ?>"></i> XOR Cipher
            </button>
            <button type="submit" name="tab" value="hash" class="nav-item flex items-center gap-4 px-8 py-3.5 text-sm font-medium text-gray-400 hover:text-gray-200 hover:bg-gray-800/40 transition-all text-left w-full <?= $activeTab=='hash'?'active':'' ?>">
                <i class="ph-duotone ph-hash w-5 text-xl <?= $activeTab=='hash'?'text-emerald-400':'' ?>"></i> SHA-256 Hash
            </button>
            <button type="submit" name="tab" value="rsa" class="nav-item flex items-center gap-4 px-8 py-3.5 text-sm font-medium text-gray-400 hover:text-gray-200 hover:bg-gray-800/40 transition-all text-left w-full <?= $activeTab=='rsa'?'active':'' ?>">
                <i class="ph-duotone ph-key w-5 text-xl <?= $activeTab=='rsa'?'text-yellow-400':'' ?>"></i> RSA System
            </button>
            <button type="submit" name="tab" value="signature" class="nav-item flex items-center gap-4 px-8 py-3.5 text-sm font-medium text-gray-400 hover:text-gray-200 hover:bg-gray-800/40 transition-all text-left w-full <?= $activeTab=='signature'?'active':'' ?>">
                <i class="ph-duotone ph-signature w-5 text-xl <?= $activeTab=='signature'?'text-pink-400':'' ?>"></i> Digital Signature
            </button>
            
            <input type="hidden" name="current_tab" value="<?= htmlspecialchars($activeTab) ?>">
            
            <?php if (!empty($textInput)) { echo '<input type="hidden" name="text" value="' . htmlspecialchars($textInput) . '">'; } ?>
            <?php if (!empty($shift) && $shift != 3) { echo '<input type="hidden" name="shift" value="' . htmlspecialchars($shift) . '">'; } ?>
            <?php if (!empty($xorKey)) { echo '<input type="hidden" name="xor_key" value="' . htmlspecialchars($xorKey) . '">'; } ?>
            <?php if (!empty($rsaPublicKey)) { echo '<input type="hidden" name="rsa_public_key" value="' . htmlspecialchars($rsaPublicKey) . '">'; } ?>
            <?php if (!empty($rsaPrivateKey)) { echo '<input type="hidden" name="rsa_private_key" value="' . htmlspecialchars($rsaPrivateKey) . '">'; } ?>
            <?php if (!empty($signatureInput)) { echo '<input type="hidden" name="signature_input" value="' . htmlspecialchars($signatureInput) . '">'; } ?>
        </form>
        
        <div class="p-6 border-t border-gray-800/80 bg-gray-950/40">
            <div class="flex items-center gap-3 text-xs text-gray-500 font-mono">
                <i class="ph-duotone ph-code text-lg text-brand-400/70"></i> Full-Stack PHP Build
            </div>
        </div>
    </aside>

    <!-- Main Content Area -->
    <main class="flex-1 flex flex-col h-full overflow-hidden relative z-10 w-full">
        
        <!-- Mobile Header -->
        <header class="md:hidden h-20 glass-card border-x-0 border-t-0 border-gray-800 flex items-center justify-between px-6 z-30 shadow-md">
            <div class="flex items-center gap-3">
                <div class="w-9 h-9 rounded-lg bg-gradient-to-br from-brand-400 to-brand-600 flex items-center justify-center border border-brand-400/30">
                    <i class="ph-duotone ph-shield-check text-white text-base"></i>
                </div>
                <h1 class="text-xl font-bold text-white tracking-tight">CryptoLens</h1>
            </div>
            <button class="text-gray-400 hover:text-white transition-colors p-2" onclick="document.getElementById('mobile-menu').classList.toggle('hidden')">
                <i class="ph ph-list text-2xl"></i>
            </button>
        </header>

        <!-- Mobile Menu Dropdown -->
        <div id="mobile-menu" class="hidden absolute top-20 left-0 w-full glass-card border-b border-gray-800 z-40 md:hidden flex flex-col backdrop-blur-2xl shadow-2xl">
            <form method="POST" action="">
                <input type="hidden" name="current_tab" value="<?= htmlspecialchars($activeTab) ?>">
                <?php if (!empty($textInput)) { echo '<input type="hidden" name="text" value="' . htmlspecialchars($textInput) . '">'; } ?>
                
                <button type="submit" name="tab" value="caesar" class="w-full text-left px-6 py-4 text-sm font-medium border-b border-gray-800/50 flex items-center gap-3 <?= $activeTab=='caesar'?'text-brand-400 bg-brand-500/10':'text-gray-400' ?>">
                    <i class="ph-duotone ph-text-aa text-xl w-6"></i> Caesar Cipher
                </button>
                 <button type="submit" name="tab" value="xor" class="w-full text-left px-6 py-4 text-sm font-medium border-b border-gray-800/50 flex items-center gap-3 <?= $activeTab=='xor'?'text-purple-400 bg-purple-500/10':'text-gray-400' ?>">
                    <i class="ph-duotone ph-arrows-left-right text-xl w-6"></i> XOR Cipher
                </button>
                <button type="submit" name="tab" value="hash" class="w-full text-left px-6 py-4 text-sm font-medium border-b border-gray-800/50 flex items-center gap-3 <?= $activeTab=='hash'?'text-emerald-400 bg-emerald-500/10':'text-gray-400' ?>">
                    <i class="ph-duotone ph-hash text-xl w-6"></i> SHA-256 Hash
                </button>
                <button type="submit" name="tab" value="rsa" class="w-full text-left px-6 py-4 text-sm font-medium border-b border-gray-800/50 flex items-center gap-3 <?= $activeTab=='rsa'?'text-yellow-400 bg-yellow-500/10':'text-gray-400' ?>">
                    <i class="ph-duotone ph-key text-xl w-6"></i> RSA Encryption
                </button>
                <button type="submit" name="tab" value="signature" class="w-full text-left px-6 py-4 text-sm font-medium flex items-center gap-3 <?= $activeTab=='signature'?'text-pink-400 bg-pink-500/10':'text-gray-400' ?>">
                    <i class="ph-duotone ph-signature text-xl w-6"></i> Digital Signature
                </button>
            </form>
        </div>

        <!-- Scrollable Workspace -->
        <div class="flex-1 overflow-y-auto custom-scrollbar px-5 py-8 md:px-12 md:py-10">
            <div class="max-w-4xl mx-auto w-full animate-enter">
                
                <!-- Tab Header -->
                <div class="mb-10">
                    <div class="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-gray-800/50 border border-gray-700/50 text-xs font-semibold tracking-wide text-gray-400 uppercase mb-4">
                        <span class="w-2 h-2 rounded-full bg-brand-500 animate-pulse shadow-[0_0_10px_rgba(99,102,241,0.8)]"></span>
                        Module Active
                    </div>
                    <h2 class="text-3xl md:text-5xl font-extrabold text-white tracking-tight flex items-center gap-3">
                        <?= str_replace('-', ' ', strtoupper($activeTab)) ?> 
                        <?= in_array($activeTab, ['rsa', 'signature']) ? '' : 'MODULE' ?>
                    </h2>
                    <p class="text-gray-400 mt-4 text-base md:text-lg max-w-2xl leading-relaxed">
                        <?php
                            $descs = [
                                'caesar' => 'Teknik substitusi sederhana dengan menggeser huruf pada alfabet.',
                                'xor' => 'Enkripsi berbasis bitwise XOR menggunakan kunci rahasia simetris.',
                                'hash' => 'Fungsi hash kriptografis yang menghasilkan nilai hash 256-bit satu arah.',
                                'rsa' => 'Kriptografi kunci asimetris yang menggunakan public key untuk enkripsi dan private key untuk dekripsi.',
                                'signature' => 'Verifikasi integritas dan otentisitas dokumen digital menggunakan kriptografi asimetris.'
                            ];
                            echo $descs[$activeTab] ?? '';
                        ?>
                    </p>
                </div>

                <!-- Errors / Alerts -->
                <?php if ($error): ?>
                    <div class="mb-8 glass-card border-red-500/30 bg-red-950/40 text-red-400 p-5 rounded-2xl flex gap-4 items-start shadow-[0_0_20px_rgba(239,68,68,0.05)] border-l-4 border-l-red-500 animate-[slideUpFade_0.3s_ease-out]">
                        <i class="ph-fill ph-warning-circle text-2xl mt-0.5"></i>
                        <div class="text-sm md:text-base font-medium leading-relaxed"><?= htmlspecialchars($error) ?></div>
                    </div>
                <?php endif; ?>

                <?php if ($result && isset($_POST['generate_keys'])): ?>
                    <div class="mb-8 glass-card border-emerald-500/30 bg-emerald-950/40 text-emerald-400 p-5 rounded-2xl flex gap-4 items-start shadow-[0_0_20px_rgba(16,185,129,0.05)] border-l-4 border-l-emerald-500 animate-[slideUpFade_0.3s_ease-out]">
                        <i class="ph-fill ph-check-circle text-2xl mt-0.5"></i>
                        <div class="text-sm md:text-base font-medium leading-relaxed"><?= htmlspecialchars($result) ?></div>
                    </div>
                <?php endif; ?>

                <!-- Form Controls -->
                <div class="glass-card rounded-2xl shadow-2xl shadow-black/50 overflow-hidden relative border-t border-t-gray-700/50">
                    <form method="POST" action="" class="p-6 md:p-8 space-y-8 relative z-10">
                        <input type="hidden" name="current_tab" value="<?= htmlspecialchars($activeTab) ?>">
                        
                        <!-- Primary Text Input -->
                        <div>
                            <label class="flex justify-between text-sm font-semibold tracking-wide text-gray-300 mb-3 uppercase">
                                <span><?= $activeTab === 'signature' && $action === 'verify' ? 'Data Asli / Dokumen' : 'Payload Data' ?></span>
                                <span class="text-gray-500 font-mono text-[10px] font-normal tracking-wider">TEXT / PLAIN</span>
                            </label>
                            <textarea name="text" rows="5" class="w-full bg-gray-900/80 border border-gray-700/80 rounded-xl p-5 text-gray-200 font-mono text-sm leading-relaxed focus:bg-gray-900 focus:border-brand-500 input-focus-glow transition-all outline-none resize-y placeholder-gray-600 custom-scrollbar shadow-inner" placeholder="// Tulis pesan, dokumen, atau payload cipher disini..." required><?= htmlspecialchars($textInput) ?></textarea>
                        </div>

                        <!-- Specific Algorithm Params -->
                        <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                            <?php if ($activeTab === 'caesar'): ?>
                                <div>
                                    <label class="block text-sm font-medium text-gray-400 mb-2">Shift Parameter (N)</label>
                                    <div class="relative">
                                        <div class="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none text-gray-500">
                                            <i class="ph ph-arrows-left-right text-lg"></i>
                                        </div>
                                        <input type="number" name="shift" value="<?= htmlspecialchars($shift) ?>" class="w-full bg-gray-900/80 border border-gray-700/80 rounded-lg pl-12 pr-4 py-3.5 text-white font-mono text-sm focus:border-brand-500 focus:bg-gray-900 input-focus-glow outline-none transition-all shadow-inner" placeholder="Misal: 3" required>
                                    </div>
                                </div>
                            <?php endif; ?>

                            <?php if ($activeTab === 'xor'): ?>
                                <div class="md:col-span-2 max-w-md">
                                    <label class="block text-sm font-medium text-gray-400 mb-2">Symmetric Key</label>
                                    <div class="relative">
                                        <div class="absolute inset-y-0 left-0 pl-4 flex items-center pointer-events-none text-gray-500">
                                            <i class="ph ph-key text-lg"></i>
                                        </div>
                                        <input type="text" name="xor_key" value="<?= htmlspecialchars($xorKey) ?>" class="w-full bg-gray-900/80 border border-gray-700/80 rounded-lg pl-12 pr-4 py-3.5 text-white font-mono text-sm focus:border-brand-500 focus:bg-gray-900 input-focus-glow outline-none transition-all shadow-inner" placeholder="Enter secret phrase..." required>
                                    </div>
                                </div>
                            <?php endif; ?>
                        </div>

                        <?php if ($activeTab === 'rsa' || $activeTab === 'signature'): ?>
                            <div class="pt-2 border-t border-gray-800/80">
                                <div class="flex items-center justify-between mb-4">
                                    <h3 class="text-sm font-medium text-gray-300 uppercase tracking-widest">Asymmetric Keys (PEM)</h3>
                                    <button type="submit" name="generate_keys" value="1" formnovalidate class="text-[11px] uppercase tracking-widest font-bold bg-gray-800 hover:bg-gray-700 text-yellow-500 border border-yellow-500/30 rounded py-1.5 px-3 transition-colors flex items-center gap-1.5">
                                        <i class="ph-bold ph-lightning"></i> Auto-Generate
                                    </button>
                                </div>
                                
                                <div class="grid grid-cols-1 xl:grid-cols-2 gap-6">
                                    <div>
                                        <label class="block text-xs font-semibold text-gray-400 mb-2 flex justify-between">
                                            <span>PUBLIC KEY</span>
                                            <span class="text-gray-500 font-mono text-[10px]">Encrypt / Verify</span>
                                        </label>
                                        <textarea name="rsa_public_key" spellcheck="false" rows="5" class="w-full bg-gray-950 border border-gray-800 rounded-lg p-3 text-gray-400 font-mono text-[11px] leading-relaxed focus:border-brand-500 outline-none block custom-scrollbar resize-y shadow-inner" placeholder="-----BEGIN PUBLIC KEY-----..."><?= htmlspecialchars($rsaPublicKey) ?></textarea>
                                    </div>
                                    <div>
                                        <label class="block text-xs font-semibold text-gray-400 mb-2 flex justify-between">
                                            <span>PRIVATE KEY</span>
                                            <span class="text-gray-500 font-mono text-[10px]">Decrypt / Sign</span>
                                        </label>
                                        <textarea name="rsa_private_key" spellcheck="false" rows="5" class="w-full bg-gray-950 border border-gray-800 rounded-lg p-3 text-gray-400 font-mono text-[11px] leading-relaxed focus:border-brand-500 outline-none block custom-scrollbar resize-y shadow-inner" placeholder="-----BEGIN PRIVATE KEY-----..."><?= htmlspecialchars($rsaPrivateKey) ?></textarea>
                                    </div>
                                </div>
                            </div>
                        <?php endif; ?>

                        <?php if ($activeTab === 'signature'): ?>
                            <div class="pt-4">
                                <label class="block text-sm font-semibold tracking-wide text-gray-300 mb-2 uppercase">Signature Hash (Verify Override)</label>
                                <textarea name="signature_input" rows="2" class="w-full bg-gray-900/80 border border-gray-700/80 rounded-xl p-4 text-pink-400 font-mono text-sm leading-relaxed focus:border-pink-500 input-focus-glow outline-none resize-y placeholder-gray-600 custom-scrollbar shadow-inner" placeholder="Masukkan base64 signature kesini jika ingin memverifikasi..."><?= htmlspecialchars($signatureInput) ?></textarea>
                            </div>
                        <?php endif; ?>

                        <!-- Execution Controls -->
                        <div class="flex flex-wrap gap-4 pt-6 border-t border-gray-800/80 bg-gray-800/10 p-6 -mx-6 md:-mx-8 -mb-6 md:-mb-8 mt-6">
                            <?php if ($activeTab === 'caesar' || $activeTab === 'xor'): ?>
                                <button type="submit" name="action" value="encrypt" class="px-8 py-3 bg-brand-600 hover:bg-brand-500 text-white text-sm font-bold tracking-wide uppercase rounded-lg shadow-[0_4px_14px_0_rgba(99,102,241,0.39)] transition-all flex items-center gap-2">
                                    <i class="ph-bold ph-lock-key"></i> Encrypt
                                </button>
                                <button type="submit" name="action" value="decrypt" class="px-8 py-3 bg-gray-800 border border-gray-700 hover:bg-gray-700 hover:border-gray-600 text-gray-200 text-sm font-bold tracking-wide uppercase rounded-lg transition-all flex items-center gap-2">
                                    <i class="ph-bold ph-lock-key-open"></i> Decrypt
                                </button>

                            <?php elseif ($activeTab === 'hash'): ?>
                                <button type="submit" name="action" value="hash" class="px-8 py-3 bg-emerald-600 hover:bg-emerald-500 text-white text-sm font-bold tracking-wide uppercase rounded-lg shadow-[0_4px_14px_0_rgba(16,185,129,0.39)] transition-all flex items-center gap-2">
                                    <i class="ph-bold ph-fingerprint"></i> Compute Hash
                                </button>

                            <?php elseif ($activeTab === 'rsa'): ?>
                                <button type="submit" name="action" value="encrypt" class="px-8 py-3 bg-brand-600 hover:bg-brand-500 text-white text-sm font-bold tracking-wide uppercase rounded-lg shadow-[0_4px_14px_0_rgba(99,102,241,0.39)] transition-all flex items-center gap-2">
                                    <i class="ph-bold ph-shield-check"></i> Encrypt with Public
                                </button>
                                <button type="submit" name="action" value="decrypt" class="px-8 py-3 bg-indigo-600 hover:bg-indigo-500 text-white text-sm font-bold tracking-wide uppercase rounded-lg shadow-[0_4px_14px_0_rgba(79,70,229,0.39)] transition-all flex items-center gap-2">
                                    <i class="ph-bold ph-shield-warning"></i> Decrypt with Private
                                </button>

                            <?php elseif ($activeTab === 'signature'): ?>
                                <button type="submit" name="action" value="sign" class="px-8 py-3 bg-pink-600 hover:bg-pink-500 text-white text-sm font-bold tracking-wide uppercase rounded-lg shadow-[0_4px_14px_0_rgba(219,39,119,0.39)] transition-all flex items-center gap-2">
                                    <i class="ph-bold ph-pen-nib"></i> Sign Document
                                </button>
                                <button type="submit" name="action" value="verify" class="px-8 py-3 bg-emerald-600 hover:bg-emerald-500 text-white text-sm font-bold tracking-wide uppercase rounded-lg shadow-[0_4px_14px_0_rgba(16,185,129,0.39)] transition-all flex items-center gap-2">
                                    <i class="ph-bold ph-checks"></i> Verify Hash
                                </button>
                            <?php endif; ?>
                        </div>
                    </form>
                </div>

                <!-- Final Output Display -->
                <?php if ($result && !isset($_POST['generate_keys'])): ?>
                    <div class="mt-8 glass-card rounded-2xl p-1 animate-enter relative overflow-hidden ring-1 ring-cyan-500/20 bg-gradient-to-br from-cyan-950/20 to-transparent">
                        <!-- Output decorative shine -->
                        <div class="absolute top-0 left-0 w-full h-[1px] bg-gradient-to-r from-transparent via-cyan-400 to-transparent opacity-50"></div>
                        
                        <div class="p-6 md:p-8 relative z-10">
                            <div class="flex justify-between items-center mb-5">
                                <h3 class="text-xs font-bold text-cyan-400 uppercase tracking-widest flex items-center gap-2">
                                    <i class="ph-bold ph-terminal-window text-base"></i> Operation Output
                                </h3>
                                <button onclick="navigator.clipboard.writeText(`<?= str_replace('`', '\`', $result) ?>`); alert('Copied Output to clipboard!');" class="text-xs font-semibold text-gray-400 hover:text-white transition-colors bg-gray-900/80 border border-gray-700/50 px-3 py-1.5 rounded flex items-center gap-2 hover:bg-gray-800">
                                    <i class="ph ph-copy"></i> Copy Value
                                </button>
                            </div>
                            
                            <div class="bg-gray-950 border border-gray-800/80 rounded-xl p-5 overflow-auto custom-scrollbar shadow-inner relative group">
                                <?php if (strpos($result, 'FAILED') !== false): ?>
                                    <pre class="font-mono text-sm text-red-400 whitespace-pre-wrap break-all leading-relaxed"><?= htmlspecialchars($result) ?></pre>
                                <?php elseif (strpos($result, 'PASSED') !== false): ?>
                                    <pre class="font-mono text-sm text-emerald-400 whitespace-pre-wrap break-all leading-relaxed"><?= htmlspecialchars($result) ?></pre>
                                <?php else: ?>
                                    <pre class="font-mono text-[13px] md:text-sm text-cyan-100 whitespace-pre-wrap break-all leading-relaxed"><?= htmlspecialchars($result) ?></pre>
                                <?php endif; ?>
                                
                                <!-- Integrated Actions within Output -->
                                <div class="mt-5 flex flex-wrap gap-3 pt-4 border-t border-gray-800/60 opacity-0 group-hover:opacity-100 transition-opacity">
                                    <!-- Send to Input Array -->
                                    <span class="text-xs font-medium text-gray-500 flex items-center mr-2">Quick Actions:</span>
                                    
                                    <button onclick="document.querySelector('textarea[name=\'text\']').value = `<?= str_replace('`', '\`', $result) ?>`; window.scrollTo({top: 0, behavior: 'smooth'});" class="text-[11px] font-bold text-brand-400 hover:text-brand-300 flex items-center transition-colors px-3 py-1.5 rounded bg-brand-500/10 hover:bg-brand-500/20 border border-brand-500/20 uppercase tracking-wider">
                                        <i class="ph-bold ph-arrow-u-down-left mr-2 text-sm"></i> Use as Input
                                    </button>
                                    
                                    <?php if ($activeTab === 'signature'): ?>
                                        <button onclick="document.querySelector('textarea[name=\'signature_input\']').value = `<?= str_replace('`', '\`', $result) ?>`; window.scrollTo({top: 0, behavior: 'smooth'});" class="text-[11px] font-bold text-pink-400 hover:text-pink-300 flex items-center transition-colors px-3 py-1.5 rounded bg-pink-500/10 hover:bg-pink-500/20 border border-pink-500/20 uppercase tracking-wider">
                                            <i class="ph-bold ph-arrow-u-down-left mr-2 text-sm"></i> Move to Hash Verify
                                        </button>
                                    <?php endif; ?>
                                </div>
                            </div>
                        </div>
                    </div>
                <?php endif; ?>

            </div>
        </div>
    </main>

</body>
</html>