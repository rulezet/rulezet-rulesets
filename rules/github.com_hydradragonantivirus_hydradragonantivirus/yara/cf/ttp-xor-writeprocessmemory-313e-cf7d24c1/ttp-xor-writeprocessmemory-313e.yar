rule TTP_XOR_WriteProcessMemory_313e {
  strings:
    $key_313e = { 66 4c [2] 54 6e [2] 52 5b [2] 7c 5b [2] 43 47 }

  condition:
    any of them
}