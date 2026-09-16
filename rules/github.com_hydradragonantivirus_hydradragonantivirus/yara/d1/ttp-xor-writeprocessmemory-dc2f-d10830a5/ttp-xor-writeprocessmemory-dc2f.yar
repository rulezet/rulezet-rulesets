rule TTP_XOR_WriteProcessMemory_dc2f {
  strings:
    $key_dc2f = { 8b 5d [2] b9 7f [2] bf 4a [2] 91 4a [2] ae 56 }

  condition:
    any of them
}