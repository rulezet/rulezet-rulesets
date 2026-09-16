rule TTP_XOR_WriteProcessMemory_db5a {
  strings:
    $key_db5a = { 8c 28 [2] be 0a [2] b8 3f [2] 96 3f [2] a9 23 }

  condition:
    any of them
}