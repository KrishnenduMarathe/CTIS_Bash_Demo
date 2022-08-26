#!/usr/bin/env bash

# Program title
CITY="=== Simple CTIS: PUNE ==="

# Except no argument
if [[ $# -ne 0 ]]; then
    echo "Arguments are not allowed"
    exit 1
else
    echo "Initializing CTIS Program"; echo
fi

# Check Users in database
function check_credentials() {
    # Return 1 if Credentials valid
    # Check Password and user from database

    cr_file="__credentials__"
    send=0

    IFS=','

    while read -r line; do

        read -ra EACH <<< $line
        if [[ $user == ${EACH[0]} ]] && [[ $pass == ${EACH[2]} ]]; then
            usertype=${EACH[1]}
            send=1
            break
        fi

    done < $cr_file

    IFS=' '

    return $send
}

usertype='false'
# User Login
count=0
clear
while [[ $count -lt 3 ]]; do
    echo -e $CITY
    echo -e "-----------  :LOGIN: ------------"
    read -p "USER:  " user
    read -s -p "PASS:  " pass

    # get sha256sum of the password
    pass=$(echo $pass | sha256sum | sed "s/  -//")

    # check user credentials
    check_credentials
    if [[ $? -ne 1 ]]; then
        clear
        echo "Wrong Credentials"; echo
    else
        break
    fi

    let "count += 1"
    if [[ $count -ge 3 ]]; then
        echo "No more login Attempts possible"
        exit 1
    fi
done

# Ask for new records

echo; echo; read -p "Do you want to add new record [y/*]: " ask

# Add data inside the database
# File format {first_name,middle_name,last_name,age,city_area,crimes_commited}
while [[ $ask == "y" ]]; do

    clear
    echo $CITY; echo

    # record new data into file
    echo "Enter Details ==>"; echo;

    read -p "Enter First Name:  " first_name
    read -p "Enter Middle Name:  " middle_name
    read -p "Enter Last Name:  " last_name
    read -p "Enter Age:  " age
    read -p "Enter Area of City:  " city_area
    read -p "Enter crimes commited (comma separated, no spaces):  " crimes_commited

    echo "$first_name,$middle_name,$last_name,$age,$city_area,$crimes_commited" | cat >> __database__

    echo; read -p "Do you want to add new record [y/*]: " ask

done

if [[ $usertype == "admin" ]]; then

    #  Add new user for administrator
    clear
    echo $CITY; echo
    read -p "Do you want to add a user [y/*]: " ask

    while [[ $ask == "y" ]]; do

        clear
        echo $CITY; echo
        read -p "USER:  " newUser
        read -p "User Type [user/admin] (lowercase only): " newType
        read -s -p "PASS:  " newPass

        # get sha256sum of the password
        newPass=$(echo $newPass | sha256sum | sed "s/  -//")

        echo "$newUser,$newType,$newPass" | cat >> __credentials__

        echo; read -p "Do you want to add a user [y/*]: " ask
    done

fi

# Functions for performing calculation and analysis

function threat_detection_of_individuals() {
    # get an individual's threat level

    db_file="__database__"

    declare -a first_list
    declare -a middle_list
    declare -a last_list
    declare -a age_cnt
    declare -a area_list
    declare -a crime_count

    position_cnt=0
    first_run=1

    while read -r line; do

        IFS=','

        read -ra EACH <<< $line

        IFS=' '

        # Get non-repeating names and attributes

        if [[ $first_run -eq 1 ]]; then

            first_list[$position_cnt]=${EACH[0]}
            middle_list[$position_cnt]=${EACH[1]}
            last_list[$position_cnt]=${EACH[2]}
            age_cnt[$position_cnt]=1
            area_list[$position_cnt]=${EACH[4]}

            array_size=${#EACH[@]}
            array_start=5
            array_end=$(( $array_size - 1 ))

            count_all_crimes=0
            for ((i = $array_start; i <= $array_end; i++)); do
                if [[ ${EACH[$i]} != '' ]]; then
                    count_all_crimes=$(( $count_all_crimes + 1 ))
                fi
            done

            crime_count[$position_cnt]=$count_all_crimes
            first_run=0
            position_cnt=$(( $position_cnt + 1 ))

        else

            current_first_name=${EACH[0]}
            current_middle_name=${EACH[1]}
            current_last_name=${EACH[2]}

            didYouFound=0
            index=0
            for ((f = 0; f < ${#first_list[@]}; f++)); do
                if [[ ${first_list[$f]} == $current_first_name ]]; then
                    index=$f

                    # Identify individual by First, Middle and Last name
                    if [[ ${middle_list[$index]} == $current_middle_name ]] && [[ ${last_list[$index]} == $current_last_name ]]; then
                        didYouFound=1
                        break
                    else
                        index=0
                    fi
                fi
            done

            if [[ $didYouFound -eq 0 ]]; then

                first_list[$position_cnt]=${EACH[0]}
                middle_list[$position_cnt]=${EACH[1]}
                last_list[$position_cnt]=${EACH[2]}
                age_cnt[$position_cnt]=1
                area_list[$position_cnt]=${EACH[4]}

                array_size=${#EACH[@]}
                array_start=5
                array_end=$(( $array_size - 1 ))

                count_all_crimes=0
                for ((i = $array_start; i <= $array_end; i++)); do
                    if [[ ${EACH[$i]} != '' ]]; then
                        count_all_crimes=$(( $count_all_crimes + 1 ))
                    fi
                done

                crime_count[$position_cnt]=$count_all_crimes
                first_run=0
                position_cnt=$(( $position_cnt + 1 ))

            else

                array_size=${#EACH[@]}
                array_start=5
                array_end=$(( $array_size - 1 ))

                count_all_crimes=0
                for ((i = $array_start; i <= $array_end; i++)); do
                    if [[ ${EACH[$i]} != '' ]]; then
                        count_all_crimes=$(( $count_all_crimes + 1 ))
                    fi
                done

                crime_count[$index]=$(( ${crime_count[$index]} + $count_all_crimes ))
                age_cnt[$index]=$(( ${age_cnt[$index]} + 1 ))

            fi

        fi

    done < $db_file

    area_cnt=${#area_list[@]}
    total_criminals=${#first_list[@]}

    total_crimes=0
    for ((i = 0; i < ${#crime_count[@]}; i++)); do
        total_crimes=$(( $total_crimes + ${crime_count[$i]} ))
    done

    # print out criminal threat level list
    echo "Threat level of Individual Criminals"; echo
    printf "%20s %20s %20s %20s\n" "FirstName" "MiddleName" "LastName" "Threat"
    echo "--------------------------------------------------------------------------------------"
    for ((i = 0; i < ${#first_list[@]}; i++)); do

        result_top=$(( $area_cnt * ${age_cnt[$i]} * 100 ))
        result_bottom=$(( ($total_crimes - ${crime_count[$i]}) * $total_criminals ))
        result=$(( $result_top / $result_bottom ))

        printf "%20s %20s %20s %20d %%\n" ${first_list[$i]} ${middle_list[$i]} ${last_list[$i]} $result

    done;
}

function threat_detection_of_area() {
    # get thread level of areas in the database

    db_file="__database__"

    declare -a all_crime_locations
    declare -a crime_locations_crime_count

    position_cnt=0
    first_run=1

    while read -r line; do

        IFS=','

        read -ra CRIMERECORD <<< $line

        IFS=' '

        if [[ $first_run -eq 1 ]]; then

            all_crime_locations[$position_cnt]=${CRIMERECORD[4]}

            array_size=${#CRIMERECORD[@]}
            array_start=5
            array_end=$(( $array_size - 1 ))

            count_all_crimes=0
            for ((i = $array_start; i <= $array_end; i++)); do
                if [[ ${CRIMERECORD[$i]} != '' ]]; then
                    count_all_crimes=$(( $count_all_crimes + 1 ))
                fi
            done

            crime_locations_crime_count[$position_cnt]=$count_all_crimes
            first_run=0
            position_cnt=$(( $position_cnt + 1 ))

        else

            current_area=${CRIMERECORD[4]}

            didYouFound=0
            index=0
            for ((r = 0; r < ${#all_crime_locations[@]}; r++)); do

                if [[ ${all_crime_locations[$r]} == $current_area ]]; then
                    index=$r
                    didYouFound=1
                    break
                else
                    index=0
                fi

            done

            if [[ $didYouFound -eq 0 ]]; then

                all_crime_locations[$position_cnt]=${CRIMERECORD[4]}

                array_size=${#CRIMERECORD[@]}
                array_start=5
                array_end=$(( $array_size - 1 ))

                count_all_crimes=0
                for ((i = $array_start; i <= $array_end; i++)); do
                    if [[ ${CRIMERECORD[$i]} != '' ]]; then
                        count_all_crimes=$(( $count_all_crimes + 1 ))
                    fi
                done

                crime_locations_crime_count[$position_cnt]=$count_all_crimes
                first_run=0
                position_cnt=$(( $position_cnt + 1 ))

            else

                array_size=${#CRIMERECORD[@]}
                array_start=5
                array_end=$(( $array_size - 1 ))

                count_all_crimes=0
                for ((i = $array_start; i <= $array_end; i++)); do
                    if [[ ${CRIMERECORD[$i]} != '' ]]; then
                        count_all_crimes=$(( $count_all_crimes + 1 ))
                    fi
                done

                crime_locations_crime_count=$(( ${crime_locations_crime_count[$index]} + $count_all_crimes ))

            fi

        fi


    done < $db_file

    # Print the list
    echo "Threat Level of Locations"; echo
    printf "\t%10s %10s\n" "Locations" "Threat"
    echo "----------------------------------"
    for ((r = 0; r < ${#all_crime_locations[@]}; r++)); do

        current_cnt=${crime_locations_crime_count[$r]}

        threat_level_area=$(( ${crime_locations_crime_count[$r]} * 100 / ${#all_crime_locations[@]} ))

        printf "\t%10s\t%d %%\n" ${all_crime_locations[$r]} $threat_level_area

    done;
}

function top_criminal_list() {
    # top criminal records in database and criminal analysis

    db_file="__database__"

    declare -a first_list
    declare -a middle_list
    declare -a last_list
    declare -a age_list
    declare -a area_list
    declare -a crime_count

    position_cnt=0
    first_run=1

    while read -r line; do

        IFS=','

        read -ra EACH <<< $line

        IFS=' '

        # Get non-repeating names and attributes

        if [[ $first_run -eq 1 ]]; then

            first_list[$position_cnt]=${EACH[0]}
            middle_list[$position_cnt]=${EACH[1]}
            last_list[$position_cnt]=${EACH[2]}
            age_list[$position_cnt]=${EACH[3]}
            area_list[$position_cnt]=${EACH[4]}

            array_size=${#EACH[@]}
            array_start=5
            array_end=$(( $array_size - 1 ))

            count_all_crimes=0
            for ((i = $array_start; i <= $array_end; i++)); do
                if [[ ${EACH[$i]} != '' ]]; then
                    count_all_crimes=$(( $count_all_crimes + 1 ))
                fi
            done

            crime_count[$position_cnt]=$count_all_crimes
            first_run=0
            position_cnt=$(( $position_cnt + 1 ))

        else

            current_first_name=${EACH[0]}
            current_middle_name=${EACH[1]}
            current_last_name=${EACH[2]}

            didYouFound=0
            index=0
            for ((f = 0; f < ${#first_list[@]}; f++)); do
                if [[ ${first_list[$f]} == $current_first_name ]]; then
                    index=$f

                    # Identify individual by First, Middle and Last name
                    if [[ ${middle_list[$index]} == $current_middle_name ]] && [[ ${last_list[$index]} == $current_last_name ]]; then
                        didYouFound=1
                        break
                    else
                        index=0
                    fi
                fi
            done

            if [[ $didYouFound -eq 0 ]]; then

                first_list[$position_cnt]=${EACH[0]}
                middle_list[$position_cnt]=${EACH[1]}
                last_list[$position_cnt]=${EACH[2]}
                age_list[$position_cnt]=${EACH[3]}
                area_list[$position_cnt]=${EACH[4]}

                array_size=${#EACH[@]}
                array_start=5
                array_end=$(( $array_size - 1 ))

                count_all_crimes=0
                for ((i = $array_start; i <= $array_end; i++)); do
                    if [[ ${EACH[$i]} != '' ]]; then
                        count_all_crimes=$(( $count_all_crimes + 1 ))
                    fi
                done

                crime_count[$position_cnt]=$count_all_crimes
                first_run=0
                position_cnt=$(( $position_cnt + 1 ))

            else

                array_size=${#EACH[@]}
                array_start=5
                array_end=$(( $array_size - 1 ))

                count_all_crimes=0
                for ((i = $array_start; i <= $array_end; i++)); do
                    if [[ ${EACH[$i]} != '' ]]; then
                        count_all_crimes=$(( $count_all_crimes + 1 ))
                    fi
                done

                crime_count[$index]=$(( ${crime_count[$index]} + $count_all_crimes ))

            fi

        fi

    done < $db_file

    # Get top 10 criminals
    echo; echo "Top 10 Criminals"; echo
    sorted_list=($(sort -r <<< ${crime_count[@]}))
    cnt=1
    stage=1

    for ((i = 0; i < ${#crime_count[@]}; i++)); do
        if [[ $(($cnt % 11)) -eq 0 ]]; then
            break
        fi

        if [[ ${sorted_list[$(( $i + 1 ))]} -ne ${sorted_list[$i]} ]]; then

            for ((j = 0; j < ${#crime_count[@]}; j++)); do
                if [[ ${crime_count[$j]} -eq ${sorted_list[$i]} ]]; then
                    printf "[$stage]:: \t%10s %10s %10s\n" ${first_list[$j]} ${middle_list[$j]} ${last_list[$j]}
                    stage=$(( $stage + 1 ))
                fi
            done

        fi

        cnt=$(( $cnt + 1 ))
    done;
}

function get_criminal_list() {
    # Get list of names of all criminals in the database
    db_file="__database__"

    echo; echo "Criminal List:"; echo
    printf "%20s %20s %20s\n" "FirstName" "MiddleName" "LastName"
    echo "-------------------------------------------------------------------------"
    while read -r line; do

        IFS=','

        read -ra EACH <<< $line

        printf "%20s %20s %20s\n" ${EACH[0]} ${EACH[1]} ${EACH[2]}

        IFS=' '

    done < $db_file

}

# Ask user what he want to do
read -p "Do you want to continue [y/*]: " ask

while [[ $ask == "y" ]]; do

    clear; echo
    echo $CITY; echo

    echo "THINGS YOU CAN DO:"
    echo "top10 -> get top 10 criminals and analysis"
    echo "list -> get list names of all criminals"
    echo "threat_area -> get threat level of all recorded area"
    echo "threat_human -> get threat level of all recorded criminals"
    echo "exit -> you know what it does"
    echo

    read -p "What to do? " whattodo
    if [[ $whattodo == "list" ]]; then
        get_criminal_list
    elif [[ $whattodo == "top10" ]]; then
        top_criminal_list
    elif [[ $whattodo == "exit" ]]; then
        break
    elif [[ $whattodo == "threat_area" ]]; then
        threat_detection_of_area
    elif [[ $whattodo == "threat_human" ]]; then
        threat_detection_of_individuals
    else
        echo "$whattodo Command Not Found!"
    fi
    echo; read -p "Press ENTER >>";
done;

# Exiting
clear
echo $CITY; echo
echo "Thank you for using Simple_CTIS"; echo
