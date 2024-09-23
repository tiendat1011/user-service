package dev.proj.userservice.utils;

public class UserUtils {
    /***
     * 1XX USER ERROR
     * 2XX USER SUCCES
     * 3XX
     */

    /***
     * 1XX
     */
    public static int USER_EXISTS_CODE = 101;
    public static String USER_EXIST_MESSAGE = "User already exists";
    public static int USER_NOT_FOUND_CODE = 104;
    public static String USER_NOT_FOUND_MESSAGE = "User not found";
    /***
     * 2XX
     */
    public static int CREATE_USER_SUCCESS_CODE = 201;
    public static String CREATE_USER_SUCCESS_MESSAGE = "User successfully created";

}
