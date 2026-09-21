# YenFuzzer

Fast directory fuzzer for web reconnaissance.

## Features

- Async engine — 100 concurrent workers
- Soft-404 detection — filters fake 200 responses
- Extension support — `-x php,txt,bak`
- Live output — results as they appear
- Clean results — only existing pages

## Install

```bash
git clone https://github.com/vnun0-yo/YenFuzzer.git
```

```bash
cd YenFuzzer
```

## install python in linux


```bash
sudo apt install python3
```

## install Libraries


```bash
sudo pip install aiohttp click rich
```
# or 

```bash
sudo pip install aiohttp click rich --break-system-packages
```
## Run The Tool 

```bash
sudo python3 YenFuzzer.py --help 
```




## simple scan

```bash
sudo python3 YenFuzzer.py -u http://localhost -w /usr/share/wordlists/dirb/common.txt
```
## Save The Scan 

```bash
sudo python3 YenFuzzer.py -u http://localhost -w /usr/share/wordlists/dirb/common.txt -o scan.txt
```


## Run The Tool Any dirctory 

```bash
cp YenFuzzer.py /usr/bin/YenFuzzer
```

```bash
chmod +x /usr/bin/YenFuzzer
```



## The Tool By Yen's 

## ---------------------------------------------------------------------------------------------------------------------------------------------------------------
