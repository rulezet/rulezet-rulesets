rule TTP_XOR_WriteProcessMemory_370d {
  strings:
    $key_370d = { 60 7f [2] 52 5d [2] 54 68 [2] 7a 68 [2] 45 74 }

  condition:
    any of them
}