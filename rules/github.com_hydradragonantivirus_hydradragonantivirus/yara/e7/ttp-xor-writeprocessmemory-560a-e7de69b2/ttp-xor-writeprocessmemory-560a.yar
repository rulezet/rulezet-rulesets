rule TTP_XOR_WriteProcessMemory_560a {
  strings:
    $key_560a = { 01 78 [2] 33 5a [2] 35 6f [2] 1b 6f [2] 24 73 }

  condition:
    any of them
}