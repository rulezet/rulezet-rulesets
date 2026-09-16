rule TTP_XOR_WriteProcessMemory_e32a {
  strings:
    $key_e32a = { b4 58 [2] 86 7a [2] 80 4f [2] ae 4f [2] 91 53 }

  condition:
    any of them
}