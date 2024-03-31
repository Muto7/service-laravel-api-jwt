<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\User;
use PHPOpenSourceSaver\JWTAuth\Facades\JWTAuth;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Auth;

class AuthController extends Controller
{
    //
    public function __construct(User $user)
    {
        // model as dependency injection
        $this->user = $user;
    }

    public function register(Request $request)
    {
        // validate the incoming request
        // set every field as required
        // set email field so it only accept the valid email format

        $validator = Validator::make($request->all(), [
            'name' => 'required|string|min:2|max:255',
            'email' => 'required|string|email:rfc,dns|max:255|unique:users',
            'password' => 'required|string|min:6|max:255',
        ]);

        //jika users sudah ada 
        if ($validator->fails()) {
            return response()->json([
                'errors' => [
                    'code' => 422,
                    'status' => 'false',
                    'message' => 'User already exist',
                    // 'details' => $validator->errors(),
                ]
            ], 422);
        }

        // if the request valid, create user

        $user = $this->user::create([
            'name' => $request['name'],
            'email' => $request['email'],
            'password' => bcrypt($request['password']),
        ]);

        // login the user immediately and generate the token
        $token = auth()->login($user);

        // return the response as json 
        return response()->json([
            'meta' => [
                'code' => 200,
                'status' => 'success',
                'message' => 'User created successfully!',
            ],
            'data' => [
                'user' => $user,
                'access_token' => [
                    'token' => $token,
                    'type' => 'Bearer',
                    'expires_in' => auth()->factory()->getTTL() * 60,    // get token expires in seconds
                ],
            ],
        ]);
    }

    public function login(Request $request)
    {
        $this->validate($request, [
            'email' => 'required|string',
            'password' => 'required|string',
        ]);

        // // Validasi input
        // if ($validator->fails()) {
        //     return response()->json([
        //         'errors' => [
        //             'code' => 422,
        //             'status' => 'false',
        //             'message' => 'Invalid input',
        //             'details' => $validator->errors(),
        //         ]
        //     ], 422);
        // }

        // Attempt untuk melakukan proses autentikasi
        if (!Auth::attempt($request->only('email', 'password'))) {
            // Jika autentikasi gagal, kembalikan pesan error
            return response()->json([
                'errors' => [
                    'code' => 401,
                    'status' => 'false',
                    'message' => 'Unauthorized',
                    'details' => 'Invalid email or password',
                ]
            ], 401);
        }

        // attempt a login (validate the credentials provided)
        $token = auth()->attempt([
            'email' => $request->email,
            'password' => $request->password,
        ]);


        // if token successfully generated then display success response
        // if attempt failed then "unauthenticated" will be returned automatically
        if ($token) {
            return response()->json([
                'meta' => [
                    'code' => 200,
                    'status' => 'success',
                    'message' => 'Quote fetched successfully.',
                ],
                'data' => [
                    'user' => auth()->user(),
                    'access_token' => [
                        'token' => $token,
                        'type' => 'Bearer',
                        'expires_in' => auth()->factory()->getTTL() * 60,
                    ],
                ],
            ]);
        }
    }

    public function logout()
    {
        // get token
        $token = JWTAuth::getToken();

        // invalidate token
        $invalidate = JWTAuth::invalidate($token);

        if ($invalidate) {
            return response()->json([
                'meta' => [
                    'code' => 200,
                    'status' => 'success',
                    'message' => 'Successfully logged out',
                ],
                'data' => [],
            ]);
        }
    }
}
