rule HARFANGLAB_Allasenhamaycampaign_Allasenha {
  meta:
    description = "Detects AllaSenha banking trojan DLLs."
    author      = "HarfangLab"
    id          = "787c4e66-2053-5f14-a52e-6b0415700e8c"
    date        = "2024-05-28"
    modified    = "2024-05-28"
    reference   = "TRR240501"
    source_url  = "https://github.com/HarfangLab/iocs/blob/f679751df7994790f9f79629d60b3f2623148255/TRR240501/trr240501_yara.yar#L21-L43"
    license_url = "N/A"
    logic_hash  = "affe75ade6c8d9eeba00006f78678a48b1cfc5ffa9f9675fdea6ffd6cb3a02bd"
    score       = 75
    quality     = 80
    tags        = ""
    context     = "file,memory"

  strings:
    $a1  = "<|NOSenha|>" wide fullword
    $a2  = "<|SENHA|>QrCode: " wide fullword
    $a3  = "<|SENHA|>Senha 6 : " wide fullword
    $a4  = "<|SENHA|>Snh: " wide fullword
    $a5  = "<|SENHA|>Token: " wide fullword
    $a6  = "<|BB-AMARELO|>" wide fullword
    $a7  = "<|BB-AZUL|>" wide fullword
    $a8  = "<|BB-PROCURADOR|>" wide fullword
    $a9  = "<|ITAU-SNH-CARTAO|>" wide fullword
    $a10 = "<|ITAU-TK-APP|>" wide fullword
    $dga = { 76 00 00 00 B0 04 02 00 FF FF FF FF 01 00 00 00 78 00 00 00 B0 04 02 00 FF FF FF FF 01 00 00 00 7A 00 00 00 B0 04 02 00 FF FF FF FF 01 00 00 00 77 00 00 00 B0 04 02 00 FF FF FF FF 01 00 00 00 6B 00 00 00 B0 04 02 00 FF FF FF FF 01 00 00 00 79 00 00 00 }

  condition:
    $dga and (4 of ($a*))
}