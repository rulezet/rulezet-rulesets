rule cloudfusion_me {
    strings: $ = "&#99;&#108;&#111;&#117;&#100;&#102;&#117;&#115;&#105;&#111;&#110;&#46;&#109;&#101;"
    condition: any of them
}