rule TTP_XOR_WriteProcessMemory_894e {
  strings:
    $key_894e = { de 3c [2] ec 1e [2] ea 2b [2] c4 2b [2] fb 37 }

  condition:
    any of them
}