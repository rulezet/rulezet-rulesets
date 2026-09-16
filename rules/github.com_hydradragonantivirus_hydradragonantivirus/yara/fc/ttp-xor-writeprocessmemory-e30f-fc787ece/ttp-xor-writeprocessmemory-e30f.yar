rule TTP_XOR_WriteProcessMemory_e30f {
  strings:
    $key_e30f = { b4 7d [2] 86 5f [2] 80 6a [2] ae 6a [2] 91 76 }

  condition:
    any of them
}