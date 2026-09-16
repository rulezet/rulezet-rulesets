rule TTP_XOR_WriteProcessMemory_e33a {
  strings:
    $key_e33a = { b4 48 [2] 86 6a [2] 80 5f [2] ae 5f [2] 91 43 }

  condition:
    any of them
}