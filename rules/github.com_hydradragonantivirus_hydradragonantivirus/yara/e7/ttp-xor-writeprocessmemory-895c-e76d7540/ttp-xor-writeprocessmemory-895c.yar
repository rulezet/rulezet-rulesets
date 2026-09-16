rule TTP_XOR_WriteProcessMemory_895c {
  strings:
    $key_895c = { de 2e [2] ec 0c [2] ea 39 [2] c4 39 [2] fb 25 }

  condition:
    any of them
}