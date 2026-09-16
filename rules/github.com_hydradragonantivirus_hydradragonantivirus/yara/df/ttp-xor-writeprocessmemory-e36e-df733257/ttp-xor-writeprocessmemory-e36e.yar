rule TTP_XOR_WriteProcessMemory_e36e {
  strings:
    $key_e36e = { b4 1c [2] 86 3e [2] 80 0b [2] ae 0b [2] 91 17 }

  condition:
    any of them
}