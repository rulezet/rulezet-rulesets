rule TTP_XOR_WriteProcessMemory_f41a {
  strings:
    $key_f41a = { a3 68 [2] 91 4a [2] 97 7f [2] b9 7f [2] 86 63 }

  condition:
    any of them
}