rule Intel_Virtualization_Wizard_dll {
  meta:
    author = "cabrel@zerklabs.com"
    description = "Dynamic DLL (Malicious)"

    file_1_seen = "2013-05-21"
    file_1_sha256 = "485ae043b6a5758789f1d33766a26d8b45b9fde09cde0512aa32d4bd1ee04f28"

  strings:
    $a = {48 3A 5C 46 61 73 74 5C 50 6C 75 67 28 68 6B 63 6D 64 29 5C}
    $b = {64 6C 6C 5C 52 65 6C 65 61 73 65 5C 48 69 6A 61 63 6B 44 6C 6C 2E 70 64 62}

  condition:
    ($a and $b) and Intel_Virtualization_Wizard_exe
}