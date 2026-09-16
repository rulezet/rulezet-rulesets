rule TTP_XOR_WriteProcessMemory_f49f {
  strings:
    $key_f49f = { a3 ed [2] 91 cf [2] 97 fa [2] b9 fa [2] 86 e6 }

  condition:
    any of them
}