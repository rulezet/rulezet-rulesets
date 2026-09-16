rule TTP_XOR_WriteProcessMemory_e23e {
  strings:
    $key_e23e = { b5 4c [2] 87 6e [2] 81 5b [2] af 5b [2] 90 47 }

  condition:
    any of them
}