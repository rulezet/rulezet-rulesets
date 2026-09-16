rule TTP_XOR_WriteProcessMemory_cd7f {
  strings:
    $key_cd7f = { 9a 0d [2] a8 2f [2] ae 1a [2] 80 1a [2] bf 06 }

  condition:
    any of them
}