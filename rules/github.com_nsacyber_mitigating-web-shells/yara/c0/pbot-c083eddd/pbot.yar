rule pbot
{
    meta:
        author = "Jacob Baines (Tenable)"

    strings:
        $ = "class pBot" ascii
        $ = "function start(" ascii
        $ = "PING" ascii
        $ = "PONG" ascii

    condition:
        all of them
}