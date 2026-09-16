rule TTP_XOR_WriteProcessMemory_891d {
  strings:
    $key_891d = { de 6f [2] ec 4d [2] ea 78 [2] c4 78 [2] fb 64 }

  condition:
    any of them
}