rule TTP_XOR_WriteProcessMemory_735d {
  strings:
    $key_735d = { 24 2f [2] 16 0d [2] 10 38 [2] 3e 38 [2] 01 24 }

  condition:
    any of them
}