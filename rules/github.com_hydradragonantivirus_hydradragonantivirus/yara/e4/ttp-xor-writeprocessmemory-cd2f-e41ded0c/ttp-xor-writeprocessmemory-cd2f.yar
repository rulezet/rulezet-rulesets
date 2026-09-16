rule TTP_XOR_WriteProcessMemory_cd2f {
  strings:
    $key_cd2f = { 9a 5d [2] a8 7f [2] ae 4a [2] 80 4a [2] bf 56 }

  condition:
    any of them
}