rule TTP_XOR_WriteProcessMemory_e80f {
  strings:
    $key_e80f = { bf 7d [2] 8d 5f [2] 8b 6a [2] a5 6a [2] 9a 76 }

  condition:
    any of them
}