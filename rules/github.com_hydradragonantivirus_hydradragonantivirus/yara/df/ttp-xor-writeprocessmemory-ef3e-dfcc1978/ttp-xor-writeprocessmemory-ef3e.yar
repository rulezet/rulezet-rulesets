rule TTP_XOR_WriteProcessMemory_ef3e {
  strings:
    $key_ef3e = { b8 4c [2] 8a 6e [2] 8c 5b [2] a2 5b [2] 9d 47 }

  condition:
    any of them
}