rule TTP_XOR_WriteProcessMemory_756a {
  strings:
    $key_756a = { 22 18 [2] 10 3a [2] 16 0f [2] 38 0f [2] 07 13 }

  condition:
    any of them
}