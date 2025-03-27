import argparse
import requests
import re
from colorama import init,Fore
import time

init(autoreset=True)
args = argparse.ArgumentParser()

args.add_argument("--url", type=str, help="Specify a single URL.")
args.add_argument("--urlist", type=str, help="Save vulnerable URLs to a file.")
args.add_argument("--output", type=str, help="to save the output.")
args.add_argument("--delay", type=int, default=0, help="Delay between requests (seconds) default=0.")

args = args.parse_args()

payload = ["<R'-\"(Checker)|<tag>>",
    "%3CR%27-%22%28Checker%29%7C%3Ctag%3E%3E%27",

            "<R'-\"Checker|<tag>>",
        "%3CR%27-%5C%22Checker%7C%3Ctag%3E%3E",

            "<R-(Checker)<tag>>",
           "%3CR%27-%28Checker%29%7C%3Ctag%3E%27",

           "<RChecker<tag>>",
            "%3CRChecker%3Ctag%3E%27"]

def url_list():
    try:
        with open(args.urlist , 'r') as wordlist:
            for urls in wordlist:
                time.sleep(args.delay)
                XSS_check(urls)
    except FileNotFoundError:
        print(f"{Fore.RED}Error: File {args.urlist} not found.")


def write_output(pass_url):
    if args.output:
        with open(args.output, 'a') as savelist:
            savelist.write(pass_url)
    else:
        pass


def single_url():
    XSS_check(args.url)

print("If Vulnerable URL found it will Display")


def reflection_validator(target_url):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    for payloads in payload:
        try:
            urls = target_url
            url = urls.replace("PAYLOAD", payloads)
            response = requests.get(url, timeout=20, headers=headers)
            if response.status_code == 200:
                output = response.text

                #Skipping because  reflection is in a "href/src/action" context
                if re.search(r'(href|src|action)="([^"]*)' + re.escape(payloads) , output):
                    print("Reflection on URL , XSS won't EXECUTE")
                    continue

                if "<R'-\"Checker|<tag>>" in output:
                    print(f"{url}  \n  {Fore.YELLOW} Potential vulnerable Endpoint Found Reflects[<,',|,-,\" >]")
                    write_output(url + " [<,',|,(-),\" >] ")
                    break #Stop testing other payloads if reflection found

                if "<R-(Checker)'<\"tag>>" in output:
                    print(f"{url}" "\n" + Fore.YELLOW + r"Vulnerable Endpoint Found Reflects[<,(,),\",>]")
                    write_output(url + "[ <,(,),\",>]")
                    break

                if "<R-(Checker)<tag>>" in output:
                    print(f"{url}" + "\n" + Fore.YELLOW + r"Vulnerable Endpoint Found Reflects[<,(,),>]")
                    write_output(url + "[<,(,),>]")
                    break

                if "<RChecker<tag>>" in output:
                    print(f"{url} \n  {Fore.YELLOW} Vulnerable Endpoint Found Reflects[<,>]")
                    write_output(url + "[<,>]")
                    break


            if response.status_code == 500:
                print(f"{url}"  + "\n" + Fore.RED +" => Getting 500 Internal Error")
                write_output(url + "500 Internal Error")


        except requests.exceptions.RequestException as e:
            pass

def XSS_check(url):
    if "?" not in url:
        return 0
    split_url = url.split("?")
    key, value = split_url
    if "&" in value:
        new_value = value.split('&')
        modified_second = []
        for new_values in new_value:
            key2,value2 = new_values.split("=")
            modified_second.append(f"{key2}=PAYLOAD")
        joining = "&".join(modified_second)
        final_url = (key + "?" + joining)
        reflection_validator(final_url)


    else:
        primary_mod = []
        key3 , value3 = split_url
        again = value3.split("=")
        key4, value4 = again
        primary_mod.append(f"{key4}=PAYLOAD")
        final2_url = (key + "?" +"=".join(primary_mod))
        reflection_validator(final2_url)


if __name__ == "__main__":
    print(f"""
    {Fore.CYAN}╔══════════════════════════════════════════════════╗
    {Fore.CYAN}║       RXSS-Checker                                                                                                     ║
    {Fore.CYAN}╚══════════════════════════════════════════════════╝

    {Fore.YELLOW}Security Notice:
    {Fore.WHITE}• This tool checks for basic syntax reflection ({Fore.RED}< ' " | -  >)
    {Fore.WHITE}• Reflection does not guarantee exploitability

    {Fore.GREEN}Scanning initialized...
    {Fore.WHITE}Potentially vulnerable URLs will appear below:
    """)

    if args.url:
        single_url()

    if args.urlist:
        url_list()
