rule TTP_XOR_WriteProcessMemory_8f7f {
  strings:
    $key_8f7f = { d8 0d [2] ea 2f [2] ec 1a [2] c2 1a [2] fd 06 }

  condition:
    any of them
}