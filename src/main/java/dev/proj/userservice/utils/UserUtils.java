package dev.proj.userservice.utils;

public class UserUtils {
    /***
     * 1XX USER ERROR
     * 2XX USER SUCCESS
     */

    /***
     * 1XX USER ERROR
     */
    public static int USER_EXISTS_CODE = 101;
    public static String USER_EXIST_MESSAGE = "User already exists";
    public static int USER_NOT_FOUND_CODE = 104;
    public static String USER_NOT_FOUND_MESSAGE = "User not found";
    /***
     * 2XX USER SUCCESS
     */
    public static int CREATE_USER_SUCCESS_CODE = 201;
    public static String CREATE_USER_SUCCESS_MESSAGE = "User successfully created";
}
