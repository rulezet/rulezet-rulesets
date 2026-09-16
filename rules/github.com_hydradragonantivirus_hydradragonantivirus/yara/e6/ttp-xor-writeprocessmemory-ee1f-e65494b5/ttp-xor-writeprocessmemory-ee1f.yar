rule TTP_XOR_WriteProcessMemory_ee1f {
  strings:
    $key_ee1f = { b9 6d [2] 8b 4f [2] 8d 7a [2] a3 7a [2] 9c 66 }

  condition:
    any of them
}