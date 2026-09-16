rule TTP_XOR_WriteProcessMemory_aa29 {
  strings:
    $key_aa29 = { fd 5b [2] cf 79 [2] c9 4c [2] e7 4c [2] d8 50 }

  condition:
    any of them
}