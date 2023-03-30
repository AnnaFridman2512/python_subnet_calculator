import re


def check_ip(ip_str):  # Will return True or False  (verify – hint: regex)
    return bool(
        re.match(r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$', ip_str))


#check_ip("192.168.0.1")

def check_CIDR(cidr):  # Cheks if CIDR valid for given IP address
    if not cidr.isdigit() or not 0 <= cidr <= 32:
        print("Enter only numbers between 0 and 32")
    else:
        cidr = int(cidr)


def calc_CIDR(ip_str):  # Calculates the CIDR by class table and return the CIDR
    ip_list = ip_str.split('.')
    first_octate = int(ip_list[0])
    print(first_octate)
    if first_octate <= 126:
        cidr = 8
    elif first_octate <= 191:
        cidr = 16
    elif first_octate <= 223:
        cidr = 24
    else:
        print("CIDR error")
    return cidr


# calc_CIDR("192.168.0.1")


"""def calc_by_host()#Should verify that input valid also

def calc_by_subnet()#Should verify that input valid also
def sub_calc():
    ip_address = input("Please enter an IP address: ")
    if ip_address:
        if check_ip(ip_address):
            user_CIDR = input("Enter CIDR")
            if user_CIDR:
                # check if CIDR is right for the IP
                check_CIDR()
            else:
                # calculate the CIDR by IP class
                calc_CIDR(ip_address)

            host_or_subnet = input("Type 'host' for calculating by hosts or type 'subnet' for calculating by number of subnets")
            if host_or_subnet == "host":
                calc_by_host()
            elif host_or_subnet == "subnet":
                calc_by_subnet()
            else:
                print("Type only subnet or host")
        else:
            print("IP not valid")
            sub_calc()
    else:
        print("Cant proseed without address")
        sub_calc()






if __name__ == '__main__':
    sub_calc()
"""
