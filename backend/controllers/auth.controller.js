import bcrypt from "bcryptjs";
import User from "../models/user.model.js";
import generateTokenAndSetCookies from "../utils/generateToken.js";

export const signup=async(req,res)=>{
    try{
        const{fullName,username,password,confrimPassword,gender}=req.body;
        if(password!==confrimPassword){
            return res.status(400).json({error:"Password don't match"})
        }

        const user=await User.findOne({username}); 
        if(user){
            return res.status(400).json({error:"User already exists"})
        }

        const salt=await bcrypt.genSalt(10);
        const hashPassword=await bcrypt.hash(password,salt);


        const boyProfilePic=`https://avatar.iran.liara.run/public/boy?username=${username}`

        const girlProfilePic=`https://avatar.iran.liara.run/public/girl?username=${username}`


        const newUser=new User({
            fullName,
            username,
            password:hashPassword,
            gender,
            profilePic: gender==="male" ?boyProfilePic :girlProfilePic,
        });
        
        if(newUser){
            generateTokenAndSetCookies(newUser._id,res);

            await newUser.save();

            res.status(201).json({
                _id:newUser._id,
                fullName:newUser.fullName,
                username:newUser.username,
                profilePic:newUser.profilePic,
            });
        }else{
            res.status(400).json({error:"Invalid user data"});
        }
        
    }catch(error){
        console.log("Error is Signup Controller", error.message);
        res.status(500).json({error:"Internal Server Error"})
    }
};

export const login=async(req,res)=>{
    try {
       const {username, password}=req.body;
       const user = await User.findOne({username});
       const isPasswordCorrect=await bcrypt.compare(password,user?.password ||"");

       if(!user || !isPasswordCorrect){
        return res.status(400).json({error:"Invalid username or password"});
       }

       generateTokenAndSetCookies(user._id,res);

       res.status(201).json({
        _id:user._id,
        fullName:user.fullName,
        username:user.username,
        profilePic:user.profilePic,
    });
       
    } catch (error) {
        console.log("Error is Login Controller", error.message);
        res.status(500).json({error:"Internal Server Error"}) 
    }
};

export const logout=(req,res)=>{
   try {
    res.cookie("jwt","",{maxAge:0});
    res.status(500).json({message:"Logged out successufully"});
    
   } catch (error) {
        console.log("Error is Logout Controller", error.message);
        res.status(500).json({error:"Internal Server Error"}) 
   }
};