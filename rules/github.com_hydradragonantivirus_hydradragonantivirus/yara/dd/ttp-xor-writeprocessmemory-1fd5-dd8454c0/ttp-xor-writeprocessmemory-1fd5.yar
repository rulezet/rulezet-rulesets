rule TTP_XOR_WriteProcessMemory_1fd5 {
  strings:
    $key_1fd5 = { 48 a7 [2] 7a 85 [2] 7c b0 [2] 52 b0 [2] 6d ac }

  condition:
    any of them
}