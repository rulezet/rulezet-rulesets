rule TTP_XOR_WriteProcessMemory_675a {
  strings:
    $key_675a = { 30 28 [2] 02 0a [2] 04 3f [2] 2a 3f [2] 15 23 }

  condition:
    any of them
}