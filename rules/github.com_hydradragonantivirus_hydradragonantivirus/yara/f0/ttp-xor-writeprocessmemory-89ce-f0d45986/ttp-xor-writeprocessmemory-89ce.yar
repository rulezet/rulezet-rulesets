rule TTP_XOR_WriteProcessMemory_89ce {
  strings:
    $key_89ce = { de bc [2] ec 9e [2] ea ab [2] c4 ab [2] fb b7 }

  condition:
    any of them
}