rule TTP_XOR_WriteProcessMemory_aa69 {
  strings:
    $key_aa69 = { fd 1b [2] cf 39 [2] c9 0c [2] e7 0c [2] d8 10 }

  condition:
    any of them
}