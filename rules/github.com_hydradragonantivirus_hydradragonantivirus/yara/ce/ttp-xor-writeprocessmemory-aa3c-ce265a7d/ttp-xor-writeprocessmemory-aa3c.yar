rule TTP_XOR_WriteProcessMemory_aa3c {
  strings:
    $key_aa3c = { fd 4e [2] cf 6c [2] c9 59 [2] e7 59 [2] d8 45 }

  condition:
    any of them
}