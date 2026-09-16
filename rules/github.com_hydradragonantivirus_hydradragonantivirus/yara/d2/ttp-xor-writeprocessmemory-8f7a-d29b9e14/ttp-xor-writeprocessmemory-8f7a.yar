rule TTP_XOR_WriteProcessMemory_8f7a {
  strings:
    $key_8f7a = { d8 08 [2] ea 2a [2] ec 1f [2] c2 1f [2] fd 03 }

  condition:
    any of them
}