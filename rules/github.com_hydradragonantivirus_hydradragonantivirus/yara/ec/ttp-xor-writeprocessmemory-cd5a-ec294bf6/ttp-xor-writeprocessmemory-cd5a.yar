rule TTP_XOR_WriteProcessMemory_cd5a {
  strings:
    $key_cd5a = { 9a 28 [2] a8 0a [2] ae 3f [2] 80 3f [2] bf 23 }

  condition:
    any of them
}