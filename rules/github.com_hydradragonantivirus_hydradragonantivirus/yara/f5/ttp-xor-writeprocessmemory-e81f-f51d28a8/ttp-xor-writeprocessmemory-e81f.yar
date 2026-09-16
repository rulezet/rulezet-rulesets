rule TTP_XOR_WriteProcessMemory_e81f {
  strings:
    $key_e81f = { bf 6d [2] 8d 4f [2] 8b 7a [2] a5 7a [2] 9a 66 }

  condition:
    any of them
}