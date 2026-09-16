rule TTP_XOR_WriteProcessMemory_763f {
  strings:
    $key_763f = { 21 4d [2] 13 6f [2] 15 5a [2] 3b 5a [2] 04 46 }

  condition:
    any of them
}