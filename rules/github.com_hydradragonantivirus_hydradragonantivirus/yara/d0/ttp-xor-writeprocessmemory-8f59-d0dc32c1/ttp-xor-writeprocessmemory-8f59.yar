rule TTP_XOR_WriteProcessMemory_8f59 {
  strings:
    $key_8f59 = { d8 2b [2] ea 09 [2] ec 3c [2] c2 3c [2] fd 20 }

  condition:
    any of them
}