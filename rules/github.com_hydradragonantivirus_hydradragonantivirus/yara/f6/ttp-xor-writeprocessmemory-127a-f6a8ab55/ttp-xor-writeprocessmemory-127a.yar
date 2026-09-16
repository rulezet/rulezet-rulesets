rule TTP_XOR_WriteProcessMemory_127a {
  strings:
    $key_127a = { 45 08 [2] 77 2a [2] 71 1f [2] 5f 1f [2] 60 03 }

  condition:
    any of them
}