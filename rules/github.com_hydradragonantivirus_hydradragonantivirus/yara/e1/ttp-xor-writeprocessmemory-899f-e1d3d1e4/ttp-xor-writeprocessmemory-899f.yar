rule TTP_XOR_WriteProcessMemory_899f {
  strings:
    $key_899f = { de ed [2] ec cf [2] ea fa [2] c4 fa [2] fb e6 }

  condition:
    any of them
}