rule TTP_XOR_WriteProcessMemory_8ffa {
  strings:
    $key_8ffa = { d8 88 [2] ea aa [2] ec 9f [2] c2 9f [2] fd 83 }

  condition:
    any of them
}