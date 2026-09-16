rule TTP_XOR_WriteProcessMemory_cd5f {
  strings:
    $key_cd5f = { 9a 2d [2] a8 0f [2] ae 3a [2] 80 3a [2] bf 26 }

  condition:
    any of them
}