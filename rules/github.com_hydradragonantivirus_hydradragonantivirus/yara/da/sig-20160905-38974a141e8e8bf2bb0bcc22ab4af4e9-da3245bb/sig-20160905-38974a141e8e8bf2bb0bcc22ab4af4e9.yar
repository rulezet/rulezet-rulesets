rule sig_20160905_38974a141e8e8bf2bb0bcc22ab4af4e9 {
  meta:
    description = "datamaliciousorder - file 20160905_38974a141e8e8bf2bb0bcc22ab4af4e9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f345a0071058dc20cb6136e2f4e08eafb1b04fe716d9d18e7119e0ae575c1e4"

  strings:
    $x1 = "objShell.ShellExecute(\"PowerShell.exe\", \"-ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -WindowStyle Hidden (New-" ascii
    $x2 = "objShell.ShellExecute(\"PowerShell.exe\", \"-ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -WindowStyle Hidden (New-" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*)
}