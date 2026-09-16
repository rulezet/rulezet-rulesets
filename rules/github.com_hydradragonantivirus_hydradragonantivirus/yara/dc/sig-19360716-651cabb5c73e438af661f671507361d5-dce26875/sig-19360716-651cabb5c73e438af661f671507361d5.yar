rule sig_19360716_651cabb5c73e438af661f671507361d5 {
  meta:
    description = "datamaliciousorder - file 19360716_651cabb5c73e438af661f671507361d5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bdf31404c58fdcb1133c236bdfea8b9918dc9626170097f4600e57e91d780ce3"

  strings:
    $s1 = "pre_which=undefined;pre_Kings=undefined;pre_group10=undefined;pre_Henry=undefined;pre_patent=undefined;pre_appears=undefined;pre" ascii
    $s2 = " \\u0057\\u0053\\u0053\\u0053\\u0031\\u0032[{d3:'\\u0053'}.d3+{l3:'\\u006c'}.l3+{th3:'\\u0065'}.th3+{im3:'\\u0065'}.im3+{ua2:'" ascii
    $s3 = "\\u0064'}.xi2+{ch3:'\\u0065'}.ch3+{ha0:'\\u0041'}.ha0+{u3:'\\u0074'}.u3](\\u0069\\u0063\\u006f\\u0075\\u006e\\u0074)) & 0xFFFFFF" ascii
    $s4 = "}.o0+{el1:'\\u006f'}.el1+{ex1:'\\u006f'}.ex1+{all0:'\\u0072'}.all0]((Math[{b0:'\\u0072'}.b0+{hi2:'\\u0061'}.hi2+{u3:'\\u006e'}.u" ascii
    $s5 = "{o0:'\\u006c'}.o0+{el1:'\\u006f'}.el1+{ex1:'\\u006f'}.ex1+{all0:'\\u0072'}.all0]((Math[{b0:'\\u0072'}.b0+{hi2:'\\u0061'}.hi2+{u3" ascii
    $s6 = "    \\u0078\\u0068\\u0072\\u0031\\u0032[{it3:'\\u006f'}.it3+{ch2:'\\u0070'}.ch2+{ar3:'\\u0065'}.ar3+{ho2:'\\u006e'}.ho2]({o1:'" ascii

  condition:
    uint16(0) == 0x7270 and
    all of them
}