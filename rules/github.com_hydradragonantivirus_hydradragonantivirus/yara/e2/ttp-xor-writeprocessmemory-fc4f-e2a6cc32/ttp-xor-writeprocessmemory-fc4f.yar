rule TTP_XOR_WriteProcessMemory_fc4f {
  strings:
    $key_fc4f = { ab 3d [2] 99 1f [2] 9f 2a [2] b1 2a [2] 8e 36 }

  condition:
    any of them
}