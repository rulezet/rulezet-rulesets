rule TTP_XOR_WriteProcessMemory_db4a {
  strings:
    $key_db4a = { 8c 38 [2] be 1a [2] b8 2f [2] 96 2f [2] a9 33 }

  condition:
    any of them
}