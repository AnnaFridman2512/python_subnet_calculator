
def check_ip() #Will return True or False  (verify – hint: regex)

def check_CIDR()#Cheks if CIDR valid for given IP address
def calc_CIDR()#Calculates the CIDR by class table and return the CIDR

def calc_by_host()#Should verify that input valid also

def calc_by_subnet()#Should verify that input valid also
def sub_calc():
    ip_address = input("Please enter an IP address: ")
    if ip_address:
        if check_ip():
            user_CIDR = input("Enter CIDR")
            if user_CIDR:
                # check if CIDR is right for the IP
                check_CIDR()
            else:
                # calculate the CIDR by IP class
                calc_CIDR()

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
